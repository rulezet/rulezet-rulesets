rule sig_20160531_96fc244903f5a934b608b755053547ab {
  meta:
    description = "datamaliciousorder - file 20160531_96fc244903f5a934b608b755053547ab.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "75af9f9f5a7a2bfd7168b8e6b174193087f0da7c3f1c11201f136ea2ac50903f"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aSAaOeww0z.length;i++)if(i%2==0)x.push(aSAaOeww0z[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}