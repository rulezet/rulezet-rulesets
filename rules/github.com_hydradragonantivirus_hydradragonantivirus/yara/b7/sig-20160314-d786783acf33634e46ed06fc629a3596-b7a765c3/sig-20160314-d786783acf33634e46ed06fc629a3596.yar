rule sig_20160314_d786783acf33634e46ed06fc629a3596 {
  meta:
    description = "datamaliciousorder - file 20160314_d786783acf33634e46ed06fc629a3596.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "84608d853efe4bdc8e735962bdf1f0abe78091ebde50a5a8220e920d68fae8ce"

  strings:
    $s1 = "MigGUWot.open(BYyKmBIQzF, gub + zAvVIVBEl + NjyDDavpUuoDn + yKLnQ + fHNSrhVtP + BXqUXGsUT + NXZNr + fvc + MOV + JiYRiom + mkJ0 +" ascii
    $s2 = "while (MigGUWot.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s3 = "return kHyLotxUMUB + qPiaxC + vbYfKarLXyY + oMmpDzOtcFY + emFezCdgZesDFP + NNGGoOn + VGftl + yNMO" fullword ascii
    $s4 = " zTimSXbIWS + JQlGXKVE + nxETvNRp + FdKOl + PmHTdw, false);" fullword ascii
    $s5 = "var ujVbyWGFo = new Date();" fullword ascii
    $s6 = "function ojHBWpgisOC(n)" fullword ascii
    $s7 = "function GqRVD(fname)" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}