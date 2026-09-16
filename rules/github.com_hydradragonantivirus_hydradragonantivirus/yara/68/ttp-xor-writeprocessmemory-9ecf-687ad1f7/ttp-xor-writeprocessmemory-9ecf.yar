rule TTP_XOR_WriteProcessMemory_9ecf {
  strings:
    $key_9ecf = { c9 bd [2] fb 9f [2] fd aa [2] d3 aa [2] ec b6 }

  condition:
    any of them
}