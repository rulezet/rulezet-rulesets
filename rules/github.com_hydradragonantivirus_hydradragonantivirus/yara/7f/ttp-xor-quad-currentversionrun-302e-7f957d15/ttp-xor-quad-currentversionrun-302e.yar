rule TTP_XOR_QUAD_CurrentVersionRun_302e {
  strings:
    $key_302e = { 63 41 [2] 47 4f [2] 6c 63 [2] 42 41 [2] 56 5a [2] 59 40 [2] 47 5d [2] 45 5c [2] 5e 5a [2] 42 5d [2] 5e 72 }

  condition:
    any of them
}