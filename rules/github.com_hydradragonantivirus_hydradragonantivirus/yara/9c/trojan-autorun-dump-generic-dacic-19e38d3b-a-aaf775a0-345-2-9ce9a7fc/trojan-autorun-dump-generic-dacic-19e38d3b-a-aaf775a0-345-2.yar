rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_345_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_345_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "75ebc3327a9adb4a9a7a78dbe0927c25d53a7e8a3cfd2fead2580e7dcbea44a4"

  strings:
    $s1 = "Vokup cubojamuruna rohuHZevexomisezub nunulavogesa wow gujogoyaxawesuh gametidiri zol dame yolekLPatiwodeyexo tenohi xerojipayak" wide
    $s2 = "Woc nipex6Tejixa tumowayoz kodabe vet xahe huxate lug puhamusoji3Fipododusuda mox gasijejucidoji jopamegexowacu dace" fullword wide
    $s3 = "?Muxarecepoho rodolax tufuzeyaluc yice lugitoyoraw xixapopizejugEZel berigufiyirom fufavayuxim lazecuhisikaw yevaravugiheke gise" wide
    $s4 = "YWiwayigucawo nasobi serifonuri nelawoluxezoto raja yofufazerobuj todovahoramej vana hutep" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}