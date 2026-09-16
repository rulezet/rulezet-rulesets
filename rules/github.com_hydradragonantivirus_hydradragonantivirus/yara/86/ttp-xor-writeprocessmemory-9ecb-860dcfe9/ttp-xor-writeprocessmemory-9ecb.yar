rule TTP_XOR_WriteProcessMemory_9ecb {
  strings:
    $key_9ecb = { c9 b9 [2] fb 9b [2] fd ae [2] d3 ae [2] ec b2 }

  condition:
    any of them
}