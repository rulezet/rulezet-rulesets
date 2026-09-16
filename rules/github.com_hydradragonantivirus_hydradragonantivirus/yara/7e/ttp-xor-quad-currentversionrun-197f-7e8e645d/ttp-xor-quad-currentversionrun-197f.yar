rule TTP_XOR_QUAD_CurrentVersionRun_197f {
  strings:
    $key_197f = { 4a 10 [2] 6e 1e [2] 45 32 [2] 6b 10 [2] 7f 0b [2] 70 11 [2] 6e 0c [2] 6c 0d [2] 77 0b [2] 6b 0c [2] 77 23 }

  condition:
    any of them
}