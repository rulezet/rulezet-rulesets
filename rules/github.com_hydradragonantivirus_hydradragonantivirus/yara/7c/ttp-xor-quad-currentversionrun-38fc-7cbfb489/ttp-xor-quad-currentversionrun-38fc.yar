rule TTP_XOR_QUAD_CurrentVersionRun_38fc {
  strings:
    $key_38fc = { 6b 93 [2] 4f 9d [2] 64 b1 [2] 4a 93 [2] 5e 88 [2] 51 92 [2] 4f 8f [2] 4d 8e [2] 56 88 [2] 4a 8f [2] 56 a0 }

  condition:
    any of them
}