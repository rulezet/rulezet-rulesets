rule TTP_XOR_QUAD_CurrentVersionRun_303f {
  strings:
    $key_303f = { 63 50 [2] 47 5e [2] 6c 72 [2] 42 50 [2] 56 4b [2] 59 51 [2] 47 4c [2] 45 4d [2] 5e 4b [2] 42 4c [2] 5e 63 }

  condition:
    any of them
}