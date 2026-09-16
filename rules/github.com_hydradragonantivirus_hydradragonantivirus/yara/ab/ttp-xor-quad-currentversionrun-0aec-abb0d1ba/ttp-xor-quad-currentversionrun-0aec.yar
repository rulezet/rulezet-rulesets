rule TTP_XOR_QUAD_CurrentVersionRun_0aec {
  strings:
    $key_0aec = { 59 83 [2] 7d 8d [2] 56 a1 [2] 78 83 [2] 6c 98 [2] 63 82 [2] 7d 9f [2] 7f 9e [2] 64 98 [2] 78 9f [2] 64 b0 }

  condition:
    any of them
}