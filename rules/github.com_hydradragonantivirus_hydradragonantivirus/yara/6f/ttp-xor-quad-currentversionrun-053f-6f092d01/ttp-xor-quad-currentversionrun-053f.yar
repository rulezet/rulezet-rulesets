rule TTP_XOR_QUAD_CurrentVersionRun_053f {
  strings:
    $key_053f = { 56 50 [2] 72 5e [2] 59 72 [2] 77 50 [2] 63 4b [2] 6c 51 [2] 72 4c [2] 70 4d [2] 6b 4b [2] 77 4c [2] 6b 63 }

  condition:
    any of them
}