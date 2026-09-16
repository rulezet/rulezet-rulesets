rule TTP_XOR_QUAD_CurrentVersionRun_503f {
  strings:
    $key_503f = { 03 50 [2] 27 5e [2] 0c 72 [2] 22 50 [2] 36 4b [2] 39 51 [2] 27 4c [2] 25 4d [2] 3e 4b [2] 22 4c [2] 3e 63 }

  condition:
    any of them
}