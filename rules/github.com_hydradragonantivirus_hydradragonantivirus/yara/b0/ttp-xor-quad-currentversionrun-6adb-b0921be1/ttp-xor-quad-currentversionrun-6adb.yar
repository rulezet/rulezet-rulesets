rule TTP_XOR_QUAD_CurrentVersionRun_6adb {
  strings:
    $key_6adb = { 39 b4 [2] 1d ba [2] 36 96 [2] 18 b4 [2] 0c af [2] 03 b5 [2] 1d a8 [2] 1f a9 [2] 04 af [2] 18 a8 [2] 04 87 }

  condition:
    any of them
}