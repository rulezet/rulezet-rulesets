rule TTP_XOR_QUAD_CurrentVersionRun_0adb {
  strings:
    $key_0adb = { 59 b4 [2] 7d ba [2] 56 96 [2] 78 b4 [2] 6c af [2] 63 b5 [2] 7d a8 [2] 7f a9 [2] 64 af [2] 78 a8 [2] 64 87 }

  condition:
    any of them
}