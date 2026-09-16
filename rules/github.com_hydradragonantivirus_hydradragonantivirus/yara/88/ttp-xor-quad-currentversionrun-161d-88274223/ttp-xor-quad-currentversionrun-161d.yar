rule TTP_XOR_QUAD_CurrentVersionRun_161d {
  strings:
    $key_161d = { 45 72 [2] 61 7c [2] 4a 50 [2] 64 72 [2] 70 69 [2] 7f 73 [2] 61 6e [2] 63 6f [2] 78 69 [2] 64 6e [2] 78 41 }

  condition:
    any of them
}