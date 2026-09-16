rule TTP_XOR_QUAD_CurrentVersionRun_301d {
  strings:
    $key_301d = { 63 72 [2] 47 7c [2] 6c 50 [2] 42 72 [2] 56 69 [2] 59 73 [2] 47 6e [2] 45 6f [2] 5e 69 [2] 42 6e [2] 5e 41 }

  condition:
    any of them
}