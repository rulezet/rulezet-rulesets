rule TTP_XOR_QUAD_CurrentVersionRun_293f {
  strings:
    $key_293f = { 7a 50 [2] 5e 5e [2] 75 72 [2] 5b 50 [2] 4f 4b [2] 40 51 [2] 5e 4c [2] 5c 4d [2] 47 4b [2] 5b 4c [2] 47 63 }

  condition:
    any of them
}