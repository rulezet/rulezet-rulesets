rule TTP_XOR_QUAD_CurrentVersionRun_15fe {
  strings:
    $key_15fe = { 46 91 [2] 62 9f [2] 49 b3 [2] 67 91 [2] 73 8a [2] 7c 90 [2] 62 8d [2] 60 8c [2] 7b 8a [2] 67 8d [2] 7b a2 }

  condition:
    any of them
}