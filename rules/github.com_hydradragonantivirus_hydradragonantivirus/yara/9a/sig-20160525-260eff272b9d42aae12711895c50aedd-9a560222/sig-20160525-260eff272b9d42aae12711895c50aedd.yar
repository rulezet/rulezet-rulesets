rule sig_20160525_260eff272b9d42aae12711895c50aedd {
  meta:
    description = "datamaliciousorder - file 20160525_260eff272b9d42aae12711895c50aedd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "794f02e1221a3be61cd4064f9cdb6d57dc5074e2248ca8654fed0d402fc91ced"

  strings:
    $s1 = "6x\\\\\"+\"c\"[gedotdarq = imq rav;\"5Q1g\" = gedotdarq rav;};keppelr nruter{)keppelr(gedotdarr noitcnuf;};suidarelcitrapr nrute" ascii
    $s2 = "fc nruter{)ecapsetihwxelfc(keppelc noitcnuf;};gedotdarc nruter{)gedotdarc(mc noitcnuf;};dnenoisillocc nruter{)dnenoisillocc(suid" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}