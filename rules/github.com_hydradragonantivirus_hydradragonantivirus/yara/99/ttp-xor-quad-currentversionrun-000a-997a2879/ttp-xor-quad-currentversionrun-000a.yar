rule TTP_XOR_QUAD_CurrentVersionRun_000a {
  strings:
    $key_000a = { 53 65 [2] 77 6b [2] 5c 47 [2] 72 65 [2] 66 7e [2] 69 64 [2] 77 79 [2] 75 78 [2] 6e 7e [2] 72 79 [2] 6e 56 }

  condition:
    any of them
}