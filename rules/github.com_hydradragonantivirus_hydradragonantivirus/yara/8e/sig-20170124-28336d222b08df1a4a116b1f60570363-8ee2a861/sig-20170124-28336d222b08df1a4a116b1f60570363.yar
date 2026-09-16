rule sig_20170124_28336d222b08df1a4a116b1f60570363 {
  meta:
    description = "datamaliciousorder - file 20170124_28336d222b08df1a4a116b1f60570363.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "715571c4f549a0875e183ae230b47f0f89bdcb92de634e3abb39a85a485a602e"

  strings:
    $s1 = "if ([\"wbillagho\", new Function([\"vujazu\", \"ywyvlen\", \"lluto\", \"raslugu\", \"ocihw\", \"rced\", \"amsymixq\", [\"iboncaw" ascii
    $s2 = "z\", \"omwaf\", \"secy\", \"gdes\", \"wajidwu\"][8] + [\"vmexy\", \"hyqyhu\", \"lyqdoc\", \"utwywrix\", \"ory\", \"otilpiqh\", " ascii
    $s3 = "\"vzarg\", \"iro\", \"jaqjuh\", \"xumil\", \"syfyrp\", \"pxiqqa\", \"deqr\", \"edxucos\", \"bhof\"][8] + [\"vedxegy\", \"ybtumzu" ascii
    $s4 = "chifbusr0 = this[[\"onwi\", \"unuw\", \"addur\", \"yqisw\", \"izyqci\", \"esjuml\", \"ybxex\", \"iqumopb\", \"gizja\", \"hefi\"," ascii
    $s5 = "chifbusr0 = this[[\"onwi\", \"unuw\", \"addur\", \"yqisw\", \"izyqci\", \"esjuml\", \"ybxex\", \"iqumopb\", \"gizja\", \"hefi\"," ascii
    $s6 = "if ([\"wbillagho\", new Function([\"vujazu\", \"ywyvlen\", \"lluto\", \"raslugu\", \"ocihw\", \"rced\", \"amsymixq\", [\"iboncaw" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}