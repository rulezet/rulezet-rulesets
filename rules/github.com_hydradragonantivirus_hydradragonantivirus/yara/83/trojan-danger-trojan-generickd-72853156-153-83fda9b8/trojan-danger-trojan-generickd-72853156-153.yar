rule Trojan_Danger_Trojan_GenericKD_72853156_153 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_153.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ac9df87389eda1cb5457a9fa8a877b9a4dc15fee64690957ce8528c6235c890b"

  strings:
    $s1 = "ckgixcfgle33\\43Wkhvdihjy`wtyv`gcxk`kkfg`wydkxtehjdjx33\\43Wglldwfgu`kctd`geld`kfui`ffekfiiulclj33;43333333=4353334533>436333544" ascii
    $s2 = ";djacacac33;43433333\\43Whvxfgvcw`cwvl`gvdy`kljv`wttdujkvxxjv33\\43Wljxtllvj`cdki`gtwg`kwyl`vhugxcxwiuee33\\43Wfjiikwfj`hcjx`gdi" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}