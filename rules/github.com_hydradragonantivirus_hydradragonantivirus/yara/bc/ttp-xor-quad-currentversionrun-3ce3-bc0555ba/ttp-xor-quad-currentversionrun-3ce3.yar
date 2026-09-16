rule TTP_XOR_QUAD_CurrentVersionRun_3ce3 {
  strings:
    $key_3ce3 = { 6f 8c [2] 4b 82 [2] 60 ae [2] 4e 8c [2] 5a 97 [2] 55 8d [2] 4b 90 [2] 49 91 [2] 52 97 [2] 4e 90 [2] 52 bf }

  condition:
    any of them
}