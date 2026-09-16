rule TTP_XOR_QUAD_CurrentVersionRun_131c {
  strings:
    $key_131c = { 40 73 [2] 64 7d [2] 4f 51 [2] 61 73 [2] 75 68 [2] 7a 72 [2] 64 6f [2] 66 6e [2] 7d 68 [2] 61 6f [2] 7d 40 }

  condition:
    any of them
}