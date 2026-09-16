rule invalid_xref_numbers_ren: PDF {
  meta:
    author      = "Glenn Edwards (@hiddenillusion)"
    version     = "0.1"
    description = "The first entry in a cross-reference table is always free and has a generation number of 65,535"
    notes       = "This can be also be in a stream..."
    weight      = 1

  strings:
    $magic = "%PDF"
    $reg0  = /xref\r?\n?.*\r?\n?.*65535\sf/
    $reg1  = /endstream.*\r?\n?endobj.*\r?\n?startxref/

  condition:
    $magic at 0 and not $reg0 and not $reg1
}