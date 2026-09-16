rule TTP_XOR_QUAD_CurrentVersionRun_b9e3 {
  strings:
    $key_b9e3 = { ea 8c [2] ce 82 [2] e5 ae [2] cb 8c [2] df 97 [2] d0 8d [2] ce 90 [2] cc 91 [2] d7 97 [2] cb 90 [2] d7 bf }

  condition:
    any of them
}