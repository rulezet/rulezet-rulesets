rule TTP_XOR_QUAD_CurrentVersionRun_20fe {
  strings:
    $key_20fe = { 73 91 [2] 57 9f [2] 7c b3 [2] 52 91 [2] 46 8a [2] 49 90 [2] 57 8d [2] 55 8c [2] 4e 8a [2] 52 8d [2] 4e a2 }

  condition:
    any of them
}