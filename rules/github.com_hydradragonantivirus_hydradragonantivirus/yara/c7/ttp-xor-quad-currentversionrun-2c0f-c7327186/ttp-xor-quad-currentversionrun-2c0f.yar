rule TTP_XOR_QUAD_CurrentVersionRun_2c0f {
  strings:
    $key_2c0f = { 7f 60 [2] 5b 6e [2] 70 42 [2] 5e 60 [2] 4a 7b [2] 45 61 [2] 5b 7c [2] 59 7d [2] 42 7b [2] 5e 7c [2] 42 53 }

  condition:
    any of them
}