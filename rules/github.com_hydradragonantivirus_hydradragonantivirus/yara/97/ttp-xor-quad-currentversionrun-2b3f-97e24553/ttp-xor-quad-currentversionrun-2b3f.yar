rule TTP_XOR_QUAD_CurrentVersionRun_2b3f {
  strings:
    $key_2b3f = { 78 50 [2] 5c 5e [2] 77 72 [2] 59 50 [2] 4d 4b [2] 42 51 [2] 5c 4c [2] 5e 4d [2] 45 4b [2] 59 4c [2] 45 63 }

  condition:
    any of them
}