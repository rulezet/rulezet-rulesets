rule _20160921_66de660457cd1dcbe458e50b91bafaca_20160921_9bf90f0e5e3e_5330 {
  meta:
    description = "datamaliciousorder - from files 20160921_66de660457cd1dcbe458e50b91bafaca.js, 20160921_9bf90f0e5e3e4249facf6ba81df47434.js, 20160921_a39f22c0c39a7d5bb3c55dd00a36b5b1.js, 20160921_d999dcba53f56b5a9c1abcc062fbeb80.js, 20160921_e927a1d46f63fcc6ccb740b1d71293f3.js, 20160922_37d3775ea966a92be28550dbc5135955.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0c92eafe23596e161cf04cc6206b7e5cac5dafb3ce36772cc5a8a4f0f827211c"
    hash2       = "7675c3fc0c8c80a2bcfa4fe026386a71ba43352c33e15df8f556bb3e96e97ab5"
    hash3       = "6a56bdeaf1decad9c4fa4ee5ac7e377d80dfd12601d1317d02f12d9d9fb19646"
    hash4       = "3bf893eeec71a95167368eb58abcbfe36362779b946b3e0d29c9032ec427ebd4"
    hash5       = "a681cf04685052da0d288a0246e49880f34a91dc46ff378f7cf1859ae526c1ef"
    hash6       = "f282b6549f474db716715761c7740ac0669f87438abd864f0e5afe9b148cb29b"

  strings:
    $s1 = "nction f000(){return \"QDg\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Go\";})(),(function f000(){retur" ascii
    $s2 = "n f000(){return \"BMj\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"" ascii
    $s3 = "turn \"NBs\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"MBb\";})()," ascii
    $s4 = ";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Sv\";})(),(function f00" ascii
    $s5 = "rn \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"MJq\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}