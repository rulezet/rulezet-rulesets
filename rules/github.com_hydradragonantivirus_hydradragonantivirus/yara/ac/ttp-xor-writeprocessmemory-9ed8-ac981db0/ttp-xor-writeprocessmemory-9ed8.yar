rule TTP_XOR_WriteProcessMemory_9ed8 {
  strings:
    $key_9ed8 = { c9 aa [2] fb 88 [2] fd bd [2] d3 bd [2] ec a1 }

  condition:
    any of them
}