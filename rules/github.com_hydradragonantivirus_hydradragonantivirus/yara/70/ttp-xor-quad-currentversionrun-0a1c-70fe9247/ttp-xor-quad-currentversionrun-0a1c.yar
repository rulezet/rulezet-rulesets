rule TTP_XOR_QUAD_CurrentVersionRun_0a1c {
  strings:
    $key_0a1c = { 59 73 [2] 7d 7d [2] 56 51 [2] 78 73 [2] 6c 68 [2] 63 72 [2] 7d 6f [2] 7f 6e [2] 64 68 [2] 78 6f [2] 64 40 }

  condition:
    any of them
}