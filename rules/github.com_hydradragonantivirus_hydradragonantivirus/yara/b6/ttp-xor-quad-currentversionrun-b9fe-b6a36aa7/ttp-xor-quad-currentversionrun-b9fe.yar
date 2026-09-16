rule TTP_XOR_QUAD_CurrentVersionRun_b9fe {
  strings:
    $key_b9fe = { ea 91 [2] ce 9f [2] e5 b3 [2] cb 91 [2] df 8a [2] d0 90 [2] ce 8d [2] cc 8c [2] d7 8a [2] cb 8d [2] d7 a2 }

  condition:
    any of them
}