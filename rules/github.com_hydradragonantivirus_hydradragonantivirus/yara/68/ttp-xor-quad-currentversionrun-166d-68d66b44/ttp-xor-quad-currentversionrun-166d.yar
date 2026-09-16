rule TTP_XOR_QUAD_CurrentVersionRun_166d {
  strings:
    $key_166d = { 45 02 [2] 61 0c [2] 4a 20 [2] 64 02 [2] 70 19 [2] 7f 03 [2] 61 1e [2] 63 1f [2] 78 19 [2] 64 1e [2] 78 31 }

  condition:
    any of them
}