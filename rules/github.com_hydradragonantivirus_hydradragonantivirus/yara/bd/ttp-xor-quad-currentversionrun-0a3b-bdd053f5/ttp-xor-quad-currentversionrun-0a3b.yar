rule TTP_XOR_QUAD_CurrentVersionRun_0a3b {
  strings:
    $key_0a3b = { 59 54 [2] 7d 5a [2] 56 76 [2] 78 54 [2] 6c 4f [2] 63 55 [2] 7d 48 [2] 7f 49 [2] 64 4f [2] 78 48 [2] 64 67 }

  condition:
    any of them
}