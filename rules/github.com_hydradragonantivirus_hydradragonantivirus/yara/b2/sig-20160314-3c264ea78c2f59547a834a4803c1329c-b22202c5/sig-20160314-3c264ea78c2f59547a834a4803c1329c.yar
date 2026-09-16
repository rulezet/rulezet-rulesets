rule sig_20160314_3c264ea78c2f59547a834a4803c1329c {
  meta:
    description = "datamaliciousorder - file 20160314_3c264ea78c2f59547a834a4803c1329c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "99b0483755a73f3744350043ba51a02de0976301f9ea4a611b51860d6d5be44d"

  strings:
    $s1 = "mgJRHloc.open(HkPidZlHxCE + tuMj, iPEd + KLae + evDx + MEUXwzQsNLDdaAa + audVHIfjYLE + krLw + rTG + lVufLcIJJEHIeC + qQvVqEbJjVe" ascii
    $s2 = "while (mgJRHloc.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s3 = "return zGmb + SsR + gaPTKIz + hHcCR + dOQfCZyLBpwBwo + CwJpkWGKCoqaZw" fullword ascii
    $s4 = "ZMBMBOh + uzgBN, false);" fullword ascii
    $s5 = "var BIeRkICeWpUo = new Date();" fullword ascii
    $s6 = "function zis(n)" fullword ascii
    $s7 = "function QdNudLyMHKuRwR(fname)" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}