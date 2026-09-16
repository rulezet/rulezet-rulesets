rule TTP_XOR_QUAD_CurrentVersionRun_093f {
  strings:
    $key_093f = { 5a 50 [2] 7e 5e [2] 55 72 [2] 7b 50 [2] 6f 4b [2] 60 51 [2] 7e 4c [2] 7c 4d [2] 67 4b [2] 7b 4c [2] 67 63 }

  condition:
    any of them
}