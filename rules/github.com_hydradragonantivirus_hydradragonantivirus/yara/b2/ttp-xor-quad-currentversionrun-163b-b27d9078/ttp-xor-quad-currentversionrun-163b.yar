rule TTP_XOR_QUAD_CurrentVersionRun_163b {
  strings:
    $key_163b = { 45 54 [2] 61 5a [2] 4a 76 [2] 64 54 [2] 70 4f [2] 7f 55 [2] 61 48 [2] 63 49 [2] 78 4f [2] 64 48 [2] 78 67 }

  condition:
    any of them
}