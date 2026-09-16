rule sig_20160525_435ba7ca67e6e6c060e692e11627c821 {
  meta:
    description = "datamaliciousorder - file 20160525_435ba7ca67e6e6c060e692e11627c821.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1909e5339e6937ce907cf2a04aac4ce8037c45a9b51eb22d3302fa3569747dad"

  strings:
    $s1 = "loch noitcnuf([rerednera[rerednera = /*  Axy KKa IlC */ sdnet rav" fullword ascii
    $s2 = "rapt + ))(};gsmt nruter{)(mt noitcnuf([eixodb    \\n;)(])deerdi(reredneri + )modnari(tsilslianbmuhtoi[eixodb    \\n         ;mb " ascii
    $s3 = "dart rav\\n;\"e67x\\\\\" = keppelt rav\\n;\"Ff6x\\\\T\" = ecapsetihwxelft rav\\n;\"56x\\\\li\" = modnart rav\\n;\"l36x\\\\\" = d" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}