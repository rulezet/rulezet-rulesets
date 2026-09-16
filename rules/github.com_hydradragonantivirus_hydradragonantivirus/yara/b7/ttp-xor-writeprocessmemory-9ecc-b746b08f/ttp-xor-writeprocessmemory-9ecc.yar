rule TTP_XOR_WriteProcessMemory_9ecc {
  strings:
    $key_9ecc = { c9 be [2] fb 9c [2] fd a9 [2] d3 a9 [2] ec b5 }

  condition:
    any of them
}