rule TTP_XOR_QUAD_CurrentVersionRun_0a40 {
  strings:
    $key_0a40 = { 59 2f [2] 7d 21 [2] 56 0d [2] 78 2f [2] 6c 34 [2] 63 2e [2] 7d 33 [2] 7f 32 [2] 64 34 [2] 78 33 [2] 64 1c }

  condition:
    any of them
}