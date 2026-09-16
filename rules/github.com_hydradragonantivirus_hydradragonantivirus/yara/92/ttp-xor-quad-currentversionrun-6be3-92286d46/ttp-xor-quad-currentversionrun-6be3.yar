rule TTP_XOR_QUAD_CurrentVersionRun_6be3 {
  strings:
    $key_6be3 = { 38 8c [2] 1c 82 [2] 37 ae [2] 19 8c [2] 0d 97 [2] 02 8d [2] 1c 90 [2] 1e 91 [2] 05 97 [2] 19 90 [2] 05 bf }

  condition:
    any of them
}