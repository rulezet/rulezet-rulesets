rule TTP_XOR_QUAD_CurrentVersionRun_5adb {
  strings:
    $key_5adb = { 09 b4 [2] 2d ba [2] 06 96 [2] 28 b4 [2] 3c af [2] 33 b5 [2] 2d a8 [2] 2f a9 [2] 34 af [2] 28 a8 [2] 34 87 }

  condition:
    any of them
}