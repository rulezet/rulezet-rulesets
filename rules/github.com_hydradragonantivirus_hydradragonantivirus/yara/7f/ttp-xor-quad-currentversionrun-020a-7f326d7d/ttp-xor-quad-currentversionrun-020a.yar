rule TTP_XOR_QUAD_CurrentVersionRun_020a {
  strings:
    $key_020a = { 51 65 [2] 75 6b [2] 5e 47 [2] 70 65 [2] 64 7e [2] 6b 64 [2] 75 79 [2] 77 78 [2] 6c 7e [2] 70 79 [2] 6c 56 }

  condition:
    any of them
}