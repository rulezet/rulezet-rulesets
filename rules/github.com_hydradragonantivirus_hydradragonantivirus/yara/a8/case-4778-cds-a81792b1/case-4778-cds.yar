rule case_4778_cds {
  meta:
    description = "4778 - file cds.xml"
    author      = "The DFIR Report"
    reference   = "https://thedfirreport.com"
    date        = "2021-08-15"
    hash1       = "5ad6dd1f4fa5b1a877f8ae61441076eb7ba3ec0d8aeb937e3db13742868babcd"

  strings:
    $s1  = " (<see cref=\"F:System.Int32.MaxValue\" /> - " fullword ascii
    $s2  = "DIO.BinaryWriter.Write(System.Decimal)\">" fullword ascii
    $s3  = " (<paramref name=\"offset\" /> + <paramref name=\"count\" /> - 1), " fullword ascii
    $s4  = " <see cref=\"T:System.InvalidOperationException\" />. </exception>" fullword ascii
    $s5  = " (<paramref name=\"index\" /> + <paramref name=\"count\" /> - 1) " fullword ascii
    $s6  = " (<paramref name=\"index + count - 1\" />) " fullword ascii
    $s7  = " (<paramref name=\"offset\" /> + <paramref name=\"count\" /> - 1) " fullword ascii
    $s8  = " <see cref=\"T:System.IO.BinaryWriter\" />, " fullword ascii
    $s9  = " <see cref=\"T:System.IO.BinaryReader\" />; " fullword ascii
    $s10 = " <see cref=\"T:System.IO.BinaryWriter\" /> " fullword ascii
    $s11 = " <see cref=\"T:System.IO.BinaryWriter\" />; " fullword ascii
    $s12 = " <see cref=\"T:System.IO.BinaryReader\" /> " fullword ascii
    $s13 = " <see cref=\"T:System.IO.BinaryReader\" /> (" fullword ascii
    $s14 = " .NET Framework " fullword ascii
    $s15 = " <member name=\"M:System.IO.BinaryReader.Read7BitEncodedInt\">" fullword ascii
    $s16 = " <see cref=\"T:System.IO.BinaryWriter\" />.</summary>" fullword ascii
    $s17 = " BinaryReader.</returns>" fullword ascii
    $s18 = " <see cref=\"T:System.IO.BinaryReader\" />.</summary>" fullword ascii
    $s19 = " -1.</returns>" fullword ascii
    $s20 = " <paramref name=\"count\" />. -" fullword ascii

  condition:
    uint16(0) == 0xbbef and filesize < 800KB and
    8 of them
}