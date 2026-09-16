rule TTP_XOR_QUAD_CurrentVersionRun_3adb {
  strings:
    $key_3adb = { 69 b4 [2] 4d ba [2] 66 96 [2] 48 b4 [2] 5c af [2] 53 b5 [2] 4d a8 [2] 4f a9 [2] 54 af [2] 48 a8 [2] 54 87 }

  condition:
    any of them
}