rule sig_20160301_8d35f433d7d32187e85c00b03c0669cd {
  meta:
    description = "datamaliciousorder - file 20160301_8d35f433d7d32187e85c00b03c0669cd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f54490a95954bd788a43b0bf029fd532d0642a316722cedb8ca692c780463871"

  strings:
    $s1 = "yardInformer = resolutionCoordination[(\"aquarium\", \"cardinal\", \"arcade\", \"ExpandEnvironmentStrings\")]((\"neutral\", \"do" ascii
    $s2 = "diameterTerrace = (((42 ^ 127), (([!+[] + !+[]] * [!+[] + !+[] + !+[]] - 1) * ([!+[] + !+[]]) * ([!+[] + !+[]] * [!+[] + !+[] + " ascii
    $s3 = "!+[]] - 1) * ([!+[] + !+[]])), (Math.pow(326, 2) - 106079)), this);" fullword ascii
    $s4 = "} catch(inspectionUnison) {};" fullword ascii
    $s5 = "while(alternativeNumeration[(\"rotation\", function String.prototype.facadeReform() {" fullword ascii

  condition:
    uint16(0) == 0x6964 and
    all of them
}