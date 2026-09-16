rule TTP_XOR_QUAD_CurrentVersionRun_45fe {
  strings:
    $key_45fe = { 16 91 [2] 32 9f [2] 19 b3 [2] 37 91 [2] 23 8a [2] 2c 90 [2] 32 8d [2] 30 8c [2] 2b 8a [2] 37 8d [2] 2b a2 }

  condition:
    any of them
}