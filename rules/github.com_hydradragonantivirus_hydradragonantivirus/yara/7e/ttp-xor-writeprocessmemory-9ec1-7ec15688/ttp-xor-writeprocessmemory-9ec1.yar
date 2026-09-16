rule TTP_XOR_WriteProcessMemory_9ec1 {
  strings:
    $key_9ec1 = { c9 b3 [2] fb 91 [2] fd a4 [2] d3 a4 [2] ec b8 }

  condition:
    any of them
}