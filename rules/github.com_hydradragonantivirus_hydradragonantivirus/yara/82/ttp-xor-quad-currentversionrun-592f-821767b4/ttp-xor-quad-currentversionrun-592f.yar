rule TTP_XOR_QUAD_CurrentVersionRun_592f {
  strings:
    $key_592f = { 0a 40 [2] 2e 4e [2] 05 62 [2] 2b 40 [2] 3f 5b [2] 30 41 [2] 2e 5c [2] 2c 5d [2] 37 5b [2] 2b 5c [2] 37 73 }

  condition:
    any of them
}