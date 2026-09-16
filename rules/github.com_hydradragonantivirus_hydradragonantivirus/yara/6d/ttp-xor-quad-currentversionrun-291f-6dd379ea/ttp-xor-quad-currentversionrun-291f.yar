rule TTP_XOR_QUAD_CurrentVersionRun_291f {
  strings:
    $key_291f = { 7a 70 [2] 5e 7e [2] 75 52 [2] 5b 70 [2] 4f 6b [2] 40 71 [2] 5e 6c [2] 5c 6d [2] 47 6b [2] 5b 6c [2] 47 43 }

  condition:
    any of them
}