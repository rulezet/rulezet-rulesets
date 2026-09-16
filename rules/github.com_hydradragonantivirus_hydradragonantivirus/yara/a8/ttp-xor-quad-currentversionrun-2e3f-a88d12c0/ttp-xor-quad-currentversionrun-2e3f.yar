rule TTP_XOR_QUAD_CurrentVersionRun_2e3f {
  strings:
    $key_2e3f = { 7d 50 [2] 59 5e [2] 72 72 [2] 5c 50 [2] 48 4b [2] 47 51 [2] 59 4c [2] 5b 4d [2] 40 4b [2] 5c 4c [2] 40 63 }

  condition:
    any of them
}