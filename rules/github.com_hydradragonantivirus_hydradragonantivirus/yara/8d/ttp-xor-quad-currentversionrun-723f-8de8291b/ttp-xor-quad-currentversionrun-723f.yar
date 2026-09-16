rule TTP_XOR_QUAD_CurrentVersionRun_723f {
  strings:
    $key_723f = { 21 50 [2] 05 5e [2] 2e 72 [2] 00 50 [2] 14 4b [2] 1b 51 [2] 05 4c [2] 07 4d [2] 1c 4b [2] 00 4c [2] 1c 63 }

  condition:
    any of them
}